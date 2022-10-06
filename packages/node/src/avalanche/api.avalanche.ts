// Copyright 2020-2022 OnFinality Limited authors & contributors
// SPDX-License-Identifier: Apache-2.0

import assert from 'assert';
import fs from 'fs';
import http from 'http';
import https from 'https';
import { Interface } from '@ethersproject/abi';
import { hexDataSlice } from '@ethersproject/bytes';
import { RuntimeDataSourceV0_2_0 } from '@subql/common-avalanche';
import { getLogger } from '@subql/node-core';
import {
  ApiWrapper,
  AvalancheLog,
  AvalancheBlockWrapper,
  AvalancheTransaction,
  AvalancheResult,
  BlockWrapper,
} from '@subql/types-avalanche';
import { Avalanche } from 'avalanche';
import { EVMAPI } from 'avalanche/dist/apis/evm';
import { BigNumber, ethers } from 'ethers';
import { AvalancheBlockWrapped } from './block.avalanche';
import { CChainProvider } from './provider';
import {
  formatBlock,
  formatReceipt,
  formatTransaction,
} from './utils.avalanche';
const Web3WsProvider = require('web3-providers-ws');

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

export class AvalancheApi implements ApiWrapper<AvalancheBlockWrapper> {
  private client: Avalanche | ethers.providers.Web3Provider;
  private genesisBlock: Record<string, any>;
  private cchain: EVMAPI;
  private contractInterfaces: Record<string, Interface> = {};
  private chainId: string;
  private callMethod: (method: string, params: any[]) => Promise<any>;
  private blockHead: number;
  protocolStr: string;
  getFinalizedBlockHeight: () => Promise<number>;

  constructor(private options: AvalancheOptions) {
    assert(options.endpoint, 'Network endpoint not provided');

    const { hostname, pathname, port, protocol, searchParams } = new URL(
      options.endpoint,
    );
    const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 10 });
    const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 10 });

    this.protocolStr = protocol.replace(':', '');
    const portNum = port
      ? parseInt(port, 10)
      : this.protocolStr === 'https'
      ? undefined
      : 80;

    if (['http', 'https'].includes(this.protocolStr)) {
      this.client = new Avalanche(
        hostname + pathname,
        portNum,
        this.protocolStr,
      );

      this.client.setRequestConfig('httpAgent', httpAgent as any);
      this.client.setRequestConfig('httpsAgent', httpsAgent as any);

      if (searchParams.get('apikey')) {
        // OnFinality supports api key via params or `apikey` header, but the api doesn't support params so we convert to header
        this.client.setHeader('apikey', searchParams.get('apikey'));
        // Support for other potential api providers
        this.client.setAuthToken(searchParams.get('apikey'));
      }

      this.client.setHeader('User-Agent', `SubQuery-Node ${packageVersion}`);

      if (this.options.token) {
        this.client.setAuthToken(this.options.token);
      }
      this.cchain = this.client.CChain();
      this.callMethod = this.rpcCall;
      this.getFinalizedBlockHeight = this.getLastHeight;
    } else if (['wss', 'ws'].includes(this.protocolStr)) {
      const wsOption = {
        headers: {
          'User-Agent': `Subquery-Node ${packageVersion}`,
        },
        clientConfig: {
          keepAlive: true,
        },
        reconnect: {
          auto: true,
          delay: 5000, // ms
          maxAttempts: 5,
          onTimeout: false,
        },
      };
      if (searchParams.get('apiKey')) {
        (wsOption.headers as any).apiKey = searchParams.get('apiKey');
      }
      const url = new URL(options.endpoint);
      url.pathname = `${url.pathname}ext/bc/C/ws`;

      const provider = new Web3WsProvider(url.toString(), options);
      this.client = new ethers.providers.Web3Provider(provider);
      this.callMethod = this.wsCall;
      this.getFinalizedBlockHeight = async () =>
        Promise.resolve(this.blockHead);
    }
  }

  async init(): Promise<void> {
    this.chainId = await this.callMethod('net_version', []);

    if (['wss', 'ws'].includes(this.protocolStr)) {
      this.blockHead = await this.getLastHeight();
      (this.client as ethers.providers.Web3Provider).on(
        'block',
        (blockNumber) => {
          this.blockHead = blockNumber;
        },
      );
    }

    this.genesisBlock = await this.callMethod('eth_getBlockByNumber', [
      '0x0',
      false,
    ]);
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

  async rpcCall(method: string, params: any[]): Promise<any> {
    const res = await this.cchain.callMethod(
      method,
      params,
      `/ext/bc/${this.options.subnet}/rpc`,
    );

    return res.data.result;
  }

  async wsCall(method: string, params: any[]): Promise<any> {
    const res = await (this.client as ethers.providers.Web3Provider).send(
      method,
      params,
    );

    return res;
  }

  async getLastHeight(): Promise<number> {
    const res = await this.callMethod('eth_blockNumber', []);

    return BigNumber.from(res).toNumber();
  }

  async fetchBlocks(bufferBlocks: number[]): Promise<AvalancheBlockWrapper[]> {
    return Promise.all(
      bufferBlocks.map(async (num) => {
        try {
          // Fetch Block
          const block_promise = await this.callMethod('eth_getBlockByNumber', [
            ethers.utils.hexValue(num),
            true,
          ]);

          const block = formatBlock(block_promise);

          // Get transaction receipts
          block.transactions = await Promise.all(
            block.transactions.map(async (tx) => {
              const transaction = formatTransaction(tx);
              const receipt = await this.callMethod(
                'eth_getTransactionReceipt',
                [tx.hash],
              );
              transaction.receipt = formatReceipt(receipt, block);
              return transaction;
            }),
          );
          return new AvalancheBlockWrapped(block);
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
    if (['https', 'http'].includes(this.protocolStr)) {
      const callMethod = async (
        method: string,
        params: any[],
        api: EVMAPI,
      ): Promise<any> => {
        const res = await api.callMethod(
          method,
          params,
          `/ext/bc/${this.options.subnet}/rpc`,
        );

        return res.data.result;
      };
      processor.freeze(
        new CChainProvider(
          this.cchain,
          callMethod,
          blockContent.blockHeight,
          `/ext/bc/${this.options.subnet}/rpc`,
        ),
        'api',
      );
    } else if (['wss', 'ws'].includes(this.protocolStr)) {
      const callMethod = async (
        method: string,
        params: any[],
        api: ethers.providers.Web3Provider,
      ): Promise<any> => {
        const res = await api.send(method, params);

        return res.data.result;
      };

      processor.freeze(
        new CChainProvider(
          this.client as ethers.providers.Web3Provider,
          callMethod,
          blockContent.blockHeight,
          `/ext/bc/${this.options.subnet}/rpc`,
        ),
        'api',
      );
    }
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
