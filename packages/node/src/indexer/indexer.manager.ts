// Copyright 2020-2022 OnFinality Limited authors & contributors
// SPDX-License-Identifier: Apache-2.0

import { Inject, Injectable } from '@nestjs/common';
import { hexToU8a, u8aEq } from '@polkadot/util';
import {
  isBlockHandlerProcessor,
  isCallHandlerProcessor,
  isEventHandlerProcessor,
  isCustomDs,
  isRuntimeDs,
  SubqlAvalancheCustomDataSource,
  SubqlCustomHandler,
  AvalancheHandlerKind,
  AvalancheRuntimeHandlerInputMap,
} from '@subql/common-avalanche';
import {
  ApiService,
  PoiBlock,
  StoreService,
  PoiService,
  NodeConfig,
  getLogger,
  profiler,
  profilerWrap,
  IndexerSandbox,
} from '@subql/node-core';
import {
  AvalancheTransaction,
  AvalancheLog,
  AvalancheBlock,
  SubqlRuntimeHandler,
  AvalancheBlockWrapper,
} from '@subql/types-avalanche';
import { Sequelize } from 'sequelize';
import { AvalancheApi } from '../avalanche/api.avalanche';
import { AvalancheBlockWrapped } from '../avalanche/block.avalanche';
import { SubqlProjectDs, SubqueryProject } from '../configure/SubqueryProject';
import { yargsOptions } from '../yargs';
import {
  asSecondLayerHandlerProcessor_1_0_0,
  DsProcessorService,
} from './ds-processor.service';
import { DynamicDsService } from './dynamic-ds.service';
import { ProjectService } from './project.service';
import { SandboxService } from './sandbox.service';

const NULL_MERKEL_ROOT = hexToU8a('0x00');

const logger = getLogger('indexer');

@Injectable()
export class IndexerManager {
  private api: AvalancheApi;
  private filteredDataSources: SubqlProjectDs[];

  constructor(
    private storeService: StoreService,
    private apiService: ApiService,
    private poiService: PoiService,
    private sequelize: Sequelize,
    @Inject('ISubqueryProject') private project: SubqueryProject,
    private nodeConfig: NodeConfig,
    private sandboxService: SandboxService,
    private dsProcessorService: DsProcessorService,
    private dynamicDsService: DynamicDsService,
    private projectService: ProjectService,
  ) {
    logger.info('indexer manager start');

    this.api = this.apiService.api;
  }

  @profiler(yargsOptions.argv.profiler)
  async indexBlock(blockContent: AvalancheBlockWrapper): Promise<{
    dynamicDsCreated: boolean;
    operationHash: Uint8Array;
    reindexBlockHeight: null;
  }> {
    const { blockHeight } = blockContent;
    let dynamicDsCreated = false;

    const tx = await this.sequelize.transaction();
    this.storeService.setTransaction(tx);
    this.storeService.setBlockHeight(blockHeight);

    let operationHash = NULL_MERKEL_ROOT;
    let poiBlockHash: Uint8Array;

    try {
      this.filteredDataSources = this.filterDataSources(blockHeight);

      const datasources = this.filteredDataSources.concat(
        ...(await this.dynamicDsService.getDynamicDatasources()),
      );

      await this.indexBlockData(
        blockContent,
        datasources,
        // eslint-disable-next-line @typescript-eslint/require-await
        async (ds: SubqlProjectDs) => {
          const vm = this.sandboxService.getDsProcessorWrapper(
            ds,
            this.api,
            blockContent,
          );

          // Inject function to create ds into vm
          vm.freeze(
            async (templateName: string, args?: Record<string, unknown>) => {
              const newDs = await this.dynamicDsService.createDynamicDatasource(
                {
                  templateName,
                  args,
                  startBlock: blockHeight,
                },
                tx,
              );
              // Push the newly created dynamic ds to be processed this block on any future extrinsics/events
              datasources.push(newDs);
              dynamicDsCreated = true;
            },
            'createDynamicDatasource',
          );

          return vm;
        },
      );

      await this.storeService.setMetadataBatch(
        [
          { key: 'lastProcessedHeight', value: blockHeight },
          { key: 'lastProcessedTimestamp', value: Date.now() },
        ],
        { transaction: tx },
      );
      // Db Metadata increase BlockCount, in memory ref to block-dispatcher _processedBlockCount
      await this.storeService.incrementJsonbCount('processedBlockCount', tx);

      // Need calculate operationHash to ensure correct offset insert all time
      operationHash = this.storeService.getOperationMerkleRoot();
      if (this.nodeConfig.proofOfIndex) {
        //check if operation is null, then poi will not be inserted
        if (!u8aEq(operationHash, NULL_MERKEL_ROOT)) {
          const poiBlock = PoiBlock.create(
            blockHeight,
            blockContent.block.hash,
            operationHash,
            await this.poiService.getLatestPoiBlockHash(),
            this.project.id,
          );
          poiBlockHash = poiBlock.hash;
          await this.storeService.setPoi(poiBlock, { transaction: tx });
          this.poiService.setLatestPoiBlockHash(poiBlockHash);
          await this.storeService.setMetadataBatch(
            [{ key: 'lastPoiHeight', value: blockHeight }],
            { transaction: tx },
          );
        }
      }
    } catch (e) {
      await tx.rollback();
      throw e;
    }

    await tx.commit();

    return {
      dynamicDsCreated,
      operationHash,
      reindexBlockHeight: null,
    };
  }

  async start(): Promise<void> {
    await this.projectService.init();
    logger.info('indexer manager started');
  }

  private filterDataSources(nextProcessingHeight: number): SubqlProjectDs[] {
    const filteredDs = this.projectService.dataSources.filter(
      (ds) => ds.startBlock <= nextProcessingHeight,
    );

    if (filteredDs.length === 0) {
      logger.error(
        `Your start block is greater than the current indexed block height in your database. Either change your startBlock (project.yaml) to <= ${nextProcessingHeight}
         or delete your database and start again from the currently specified startBlock`,
      );
      process.exit(1);
    }
    // perform filter for custom ds
    if (!filteredDs.length) {
      logger.error(`Did not find any datasources with associated processor`);
      process.exit(1);
    }
    return filteredDs;
  }

  private async indexBlockData(
    { block, logs, transactions }: AvalancheBlockWrapper,
    dataSources: SubqlProjectDs[],
    getVM: (d: SubqlProjectDs) => Promise<IndexerSandbox>,
  ): Promise<void> {
    await this.indexBlockContent(block, dataSources, getVM);

    for (const log of logs) {
      await this.indexEvent(log, dataSources, getVM);
    }

    for (const tx of transactions) {
      await this.indexExtrinsic(tx, dataSources, getVM);
    }
  }

  private async indexBlockContent(
    block: AvalancheBlock,
    dataSources: SubqlProjectDs[],
    getVM: (d: SubqlProjectDs) => Promise<IndexerSandbox>,
  ): Promise<void> {
    for (const ds of dataSources) {
      await this.indexData(AvalancheHandlerKind.Block, block, ds, getVM);
    }
  }

  private async indexExtrinsic(
    tx: AvalancheTransaction,
    dataSources: SubqlProjectDs[],
    getVM: (d: SubqlProjectDs) => Promise<IndexerSandbox>,
  ): Promise<void> {
    for (const ds of dataSources) {
      await this.indexData(AvalancheHandlerKind.Call, tx, ds, getVM);
    }
  }

  private async indexEvent(
    log: AvalancheLog,
    dataSources: SubqlProjectDs[],
    getVM: (d: SubqlProjectDs) => Promise<IndexerSandbox>,
  ): Promise<void> {
    for (const ds of dataSources) {
      await this.indexData(AvalancheHandlerKind.Event, log, ds, getVM);
    }
  }

  private async indexData<K extends AvalancheHandlerKind>(
    kind: K,
    data: AvalancheRuntimeHandlerInputMap[K],
    ds: SubqlProjectDs,
    getVM: (ds: SubqlProjectDs) => Promise<IndexerSandbox>,
  ): Promise<void> {
    let vm: IndexerSandbox;
    if (isRuntimeDs(ds)) {
      const handlers = (ds.mapping.handlers as SubqlRuntimeHandler[]).filter(
        (h) =>
          h.kind === kind &&
          FilterTypeMap[kind](
            data as any,
            h.filter as any,
            ds.options?.address,
          ),
      );

      if (!handlers.length) {
        return;
      }
      const parsedData = await DataAbiParser[kind](this.api)(data, ds);

      for (const handler of handlers) {
        vm = vm ?? (await getVM(ds));
        this.nodeConfig.profiler
          ? await profilerWrap(
              vm.securedExec.bind(vm),
              'handlerPerformance',
              handler.handler,
            )(handler.handler, [parsedData])
          : await vm.securedExec(handler.handler, [parsedData]);
      }
    } else if (isCustomDs(ds)) {
      const handlers = this.filterCustomDsHandlers<K>(
        ds,
        data,
        ProcessorTypeMap[kind],
        (data, baseFilter) => {
          switch (kind) {
            case AvalancheHandlerKind.Block:
              return AvalancheBlockWrapped.filterBlocksProcessor(
                data as AvalancheBlock,
                baseFilter,
              );
            case AvalancheHandlerKind.Call:
              return AvalancheBlockWrapped.filterTransactionsProcessor(
                data as AvalancheTransaction,
                baseFilter,
              );
            case AvalancheHandlerKind.Event:
              return AvalancheBlockWrapped.filterLogsProcessor(
                data as AvalancheLog,
                baseFilter,
              );
            default:
              throw new Error('Unsupported handler kind');
          }
        },
      );

      if (!handlers.length) {
        return;
      }

      const parsedData = await DataAbiParser[kind](this.api)(data, ds);

      for (const handler of handlers) {
        vm = vm ?? (await getVM(ds));
        await this.transformAndExecuteCustomDs(ds, vm, handler, parsedData);
      }
    }
  }

  private filterCustomDsHandlers<K extends AvalancheHandlerKind>(
    ds: SubqlAvalancheCustomDataSource<string, any>,
    data: AvalancheRuntimeHandlerInputMap[K],
    baseHandlerCheck: ProcessorTypeMap[K],
    baseFilter: (
      data: AvalancheRuntimeHandlerInputMap[K],
      baseFilter: any,
    ) => boolean,
  ): SubqlCustomHandler[] {
    const plugin = this.dsProcessorService.getDsProcessor(ds);

    return ds.mapping.handlers
      .filter((handler) => {
        const processor = plugin.handlerProcessors[handler.kind];
        if (baseHandlerCheck(processor)) {
          processor.baseFilter;

          return baseFilter(data, processor.baseFilter);
        }
        return false;
      })
      .filter((handler) => {
        const processor = asSecondLayerHandlerProcessor_1_0_0(
          plugin.handlerProcessors[handler.kind],
        );

        try {
          return processor.filterProcessor({
            filter: handler.filter,
            input: data,
            ds,
          });
        } catch (e) {
          logger.error(e, 'Failed to run ds processer filter.');
          throw e;
        }
      });
  }

  private async transformAndExecuteCustomDs<K extends AvalancheHandlerKind>(
    ds: SubqlAvalancheCustomDataSource<string, any>,
    vm: IndexerSandbox,
    handler: SubqlCustomHandler,
    data: AvalancheRuntimeHandlerInputMap[K],
  ): Promise<void> {
    const plugin = this.dsProcessorService.getDsProcessor(ds);
    const assets = await this.dsProcessorService.getAssets(ds);

    const processor = asSecondLayerHandlerProcessor_1_0_0(
      plugin.handlerProcessors[handler.kind],
    );

    const transformedData = await processor
      .transformer({
        input: data,
        ds,
        api: this.api,
        filter: handler.filter,
        assets,
      })
      .catch((e) => {
        logger.error(e, 'Failed to transform data with ds processor.');
        throw e;
      });

    // We can not run this in parallel. the transformed data items may be dependent on one another.
    // An example of this is with Acala EVM packing multiple EVM logs into a single Substrate event
    for (const _data of transformedData) {
      await vm.securedExec(handler.handler, [_data]);
    }
  }
}

type ProcessorTypeMap = {
  [AvalancheHandlerKind.Block]: typeof isBlockHandlerProcessor;
  [AvalancheHandlerKind.Event]: typeof isEventHandlerProcessor;
  [AvalancheHandlerKind.Call]: typeof isCallHandlerProcessor;
};

const ProcessorTypeMap = {
  [AvalancheHandlerKind.Block]: isBlockHandlerProcessor,
  [AvalancheHandlerKind.Event]: isEventHandlerProcessor,
  [AvalancheHandlerKind.Call]: isCallHandlerProcessor,
};

const FilterTypeMap = {
  [AvalancheHandlerKind.Block]: AvalancheBlockWrapped.filterBlocksProcessor,
  [AvalancheHandlerKind.Event]: AvalancheBlockWrapped.filterLogsProcessor,
  [AvalancheHandlerKind.Call]:
    AvalancheBlockWrapped.filterTransactionsProcessor,
};

const DataAbiParser = {
  [AvalancheHandlerKind.Block]: () => (data: AvalancheBlock) => data,
  [AvalancheHandlerKind.Event]: (api: AvalancheApi) => api.parseLog.bind(api),
  [AvalancheHandlerKind.Call]: (api: AvalancheApi) =>
    api.parseTransaction.bind(api),
};
