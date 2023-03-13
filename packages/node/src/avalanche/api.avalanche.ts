// Copyright 2020-2022 OnFinality Limited authors & contributors
// SPDX-License-Identifier: Apache-2.0

import assert from 'assert';
import fs from 'fs';
import http from 'http';
import https from 'https';
import { Interface } from '@ethersproject/abi';
import { hexDataSlice } from '@ethersproject/bytes';
import { RuntimeDataSourceV0_2_0 } from '@subql/common-avalanche';
import { getLogger, retryOnFailAxios } from '@subql/node-core';
import {
  ApiWrapper,
  AvalancheLog,
  AvalancheBlockWrapper,
  AvalancheTransaction,
  AvalancheResult,
  BlockWrapper,
  AvalancheBlock,
} from '@subql/types-avalanche';
import { Avalanche } from 'avalanche';
import { EVMAPI } from 'avalanche/dist/apis/evm';
import { IndexAPI } from 'avalanche/dist/apis/index';
import { RequestResponseData } from 'avalanche/dist/common';
import { BigNumber } from 'ethers';
import { AvalancheBlockWrapped } from './block.avalanche';
import { CChainProvider } from './provider';
import {
  formatBlock,
  formatReceipt,
  formatTransaction,
} from './utils.avalanche';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { version: packageVersion } = require('../../package.json');

type AvalancheOptions = {
  endpoint?: string;
  token?: string;
  chainId: string; //'XV' | 'XT' | 'C' | 'P';
  subnet: string;
};

const logger = getLogger('api.avalanche');

async function loadAssets(
  ds: RuntimeDataSourceV0_2_0,
): Promise<Record<string, string>> {
  if (!ds.assets) {
    return {};
  }
  const res: Record<string, string> = {};

  for (const [name, { file }] of Object.entries(ds.assets)) {
    try {
      res[name] = await fs.promises.readFile(file, { encoding: 'utf8' });
    } catch (e) {
      throw new Error(`Failed to load datasource asset ${file}`);
    }
  }

  return res;
}

const RETRY_STATUS_CODE = [429];

export class AvalancheApi implements ApiWrapper<AvalancheBlockWrapper> {
  private client: Avalanche;
  private indexApi: IndexAPI;
  private genesisBlock: Record<string, any>;
  private encoding: string;
  private baseUrl: string;
  private cchain: EVMAPI;
  private contractInterfaces: Record<string, Interface> = {};
  private chainId: string;

  constructor(private options: AvalancheOptions) {
    this.encoding = 'cb58';

    assert(options.endpoint, 'Network endpoint not provided');

    const { hostname, pathname, port, protocol, searchParams } = new URL(
      options.endpoint,
    );
    const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 10 });
    const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 10 });

    const protocolStr = protocol.replace(':', '');
    const portNum = port
      ? parseInt(port, 10)
      : protocolStr === 'https'
      ? undefined
      : 80;

    this.client = new Avalanche(hostname + pathname, portNum, protocolStr);

    this.client.setRequestConfig('httpAgent', httpAgent as any);
    this.client.setRequestConfig('httpsAgent', httpsAgent as any);

    if (searchParams.get('apikey')) {
      // OnFinality supports api key via params or `apikey` header, but the api doesn't support params so we convert to header
      this.client.setHeader('apikey', searchParams.get('apikey'));
      // Support for other potential api providers
      this.client.setAuthToken(searchParams.get('apikey'));
    }

    if (this.options.token) {
      this.client.setAuthToken(this.options.token);
    }
    this.indexApi = this.client.Index();
    this.cchain = this.client.CChain();

    switch (this.options.subnet) {
      case 'XV':
        this.baseUrl = '/ext/index/X/vtx';
        break;
      case 'XT':
        this.baseUrl = '/ext/index/X/tx';
        break;
      case 'C':
        this.baseUrl = '/ext/index/C/block';
        break;
      case 'P':
        this.baseUrl = '/ext/index/P/block';
        break;
      default:
        this.baseUrl = `/ext/index/${this.options.subnet}/block`;
        break;
    }
  }

  async init(): Promise<void> {
    this.chainId = await this.client.Info().getNetworkName();

    this.client.setHeader('User-Agent', `SubQuery-Node ${packageVersion}`);

    this.genesisBlock = (
      await this.cchain.callMethod(
        'eth_getBlockByNumber',
        ['0x0', true],
        `/ext/bc/${this.options.subnet}/rpc`,
      )
    ).data.result;
  }

  getChainId(): string {
    return this.chainId;
  }

  getGenesisHash(): string {
    return this.genesisBlock.hash;
  }

  getRuntimeChain(): string /*'XV' | 'XT' | 'C' | 'P'*/ {
    return this.options.chainId;
  }

  getSpecName(): string {
    return 'avalanche';
  }

  async getFinalizedBlockHeight(): Promise<number> {
    // Doesn't seem to be a difference between finalized and latest
    return this.getLastHeight();
  }

  async getLastHeight(): Promise<number> {
    const res = await this.cchain.callMethod(
      'eth_blockNumber',
      [],
      `/ext/bc/${this.options.subnet}/rpc`,
    );

    return BigNumber.from(res.data.result).toNumber();
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async getCallMethod(
    method: string,
    params: any[],
  ): Promise<RequestResponseData> {
    return retryOnFailAxios<RequestResponseData>(
      this.cchain.callMethod.bind(
        this.cchain,
        method,
        params,
        `/ext/bc/${this.options.subnet}/rpc`,
      ),
      RETRY_STATUS_CODE,
    );
  }

  async transactionReceipts(
    tx: AvalancheTransaction,
    num: number,
    block: AvalancheBlock,
  ): Promise<AvalancheTransaction<AvalancheResult>> {
    const transaction = formatTransaction(tx);
    const receipt = (
      await this.getCallMethod('eth_getTransactionReceipt', [tx.hash])
    ).data.result;
    transaction.receipt = formatReceipt(receipt, block);
    return transaction;
  }

  async fetchBlock(num: number): Promise<AvalancheBlockWrapper> {
    const block_promise = await this.getCallMethod('eth_getBlockByNumber', [
      `0x${num.toString(16)}`,
      true,
    ]);

    const block = formatBlock(block_promise.data.result);

    // Get transaction receipts
    block.transactions = await Promise.all(
      block.transactions.map(async (tx) =>
        this.transactionReceipts(tx, num, block),
      ),
    );
    return new AvalancheBlockWrapped(block);
  }

  async fetchBlocks(bufferBlocks: number[]): Promise<AvalancheBlockWrapper[]> {
    return Promise.all(
      bufferBlocks.map(async (num) => {
        try {
          return await this.fetchBlock(num);
        } catch (e) {
          // Wrap error from an axios error to fix issue with error being undefined
          const error = new Error(e.message);
          logger.error(error, `Failed to fetch block at height ${num}`);
          throw error;
        }
      }),
    );
  }

  freezeApi(processor: any, blockContent: BlockWrapper): void {
    processor.freeze(
      new CChainProvider(
        this.client,
        blockContent.blockHeight,
        `/ext/bc/${this.options.subnet}/rpc`,
      ),
      'api',
    );
  }

  private buildInterface(
    abiName: string,
    assets: Record<string, string>,
  ): Interface | undefined {
    if (!assets[abiName]) {
      throw new Error(`ABI named "${abiName}" not referenced in assets`);
    }

    // This assumes that all datasources have a different abi name or they are the same abi
    if (!this.contractInterfaces[abiName]) {
      // Constructing the interface validates the ABI
      try {
        let abiObj = JSON.parse(assets[abiName]);

        /*
         * Allows parsing JSON artifacts as well as ABIs
         * https://trufflesuite.github.io/artifact-updates/background.html#what-are-artifacts
         */
        if (!Array.isArray(abiObj) && abiObj.abi) {
          abiObj = abiObj.abi;
        }

        this.contractInterfaces[abiName] = new Interface(abiObj);
      } catch (e) {
        logger.error(`Unable to parse ABI: ${e.message}`);
        throw new Error('ABI is invalid');
      }
    }

    return this.contractInterfaces[abiName];
  }

  async parseLog<T extends AvalancheResult = AvalancheResult>(
    log: AvalancheLog,
    ds: RuntimeDataSourceV0_2_0,
  ): Promise<AvalancheLog<T> | AvalancheLog> {
    try {
      if (!ds?.options?.abi) {
        logger.warn('No ABI provided for datasource');
        return log;
      }
      const iface = this.buildInterface(ds.options.abi, await loadAssets(ds));
      return {
        ...log,
        args: iface?.parseLog(log).args as T,
      };
    } catch (e) {
      logger.warn(`Failed to parse log data: ${e.message}`);
      return log;
    }
  }

  async parseTransaction<T extends AvalancheResult = AvalancheResult>(
    transaction: AvalancheTransaction,
    ds: RuntimeDataSourceV0_2_0,
  ): Promise<AvalancheTransaction<T> | AvalancheTransaction> {
    try {
      if (!ds?.options?.abi) {
        logger.warn('No ABI provided for datasource');
        return transaction;
      }
      const assets = await loadAssets(ds);
      const iface = this.buildInterface(ds.options.abi, assets);
      const func = iface.getFunction(hexDataSlice(transaction.input, 0, 4));
      const args = iface.decodeFunctionData(func, transaction.input) as T;
      return {
        ...transaction,
        args,
      };
    } catch (e) {
      logger.warn(`Failed to parse transaction data: ${e.message}`);
      return transaction;
    }
  }
}
