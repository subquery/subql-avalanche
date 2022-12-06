// Copyright 2020-2021 OnFinality Limited authors & contributors
// SPDX-License-Identifier: Apache-2.0

import { Injectable, OnApplicationShutdown } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import {
  getLogger,
  NodeConfig,
  IndexerEvent,
  delay,
  profilerWrap,
  AutoQueue,
  Queue,
  ApiService,
} from '@subql/node-core';
import { last } from 'lodash';
import { IndexerManager } from '../indexer.manager';
import { ProjectService } from '../project.service';
import { BaseBlockDispatcher } from './base-block-dispatcher';

const logger = getLogger('BlockDispatcherService');

/**
 * @description Intended to behave the same as WorkerBlockDispatcherService but doesn't use worker threads or any parallel processing
 */
@Injectable()
export class BlockDispatcherService
  extends BaseBlockDispatcher<Queue<number>>
  implements OnApplicationShutdown
{
  private processQueue: AutoQueue<void>;

  private fetching = false;
  private isShutdown = false;
  private fetchBlocksBatches: ApiService['api']['fetchBlocks'];

  constructor(
    private apiService: ApiService,
    nodeConfig: NodeConfig,
    private indexerManager: IndexerManager,
    eventEmitter: EventEmitter2,
    projectService: ProjectService,
  ) {
    super(
      nodeConfig,
      eventEmitter,
      projectService,
      new Queue(nodeConfig.batchSize * 3),
    );
    this.processQueue = new AutoQueue(nodeConfig.batchSize * 3);

    const fetchBlocks = this.apiService.api.fetchBlocks.bind(
      this.apiService.api,
    );
    if (this.nodeConfig.profiler) {
      this.fetchBlocksBatches = profilerWrap(
        fetchBlocks,
        'AvalancheUtil',
        'fetchBlocksBatches',
      );
    } else {
      this.fetchBlocksBatches = fetchBlocks;
    }
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async init(
    onDynamicDsCreated: (height: number) => Promise<void>,
  ): Promise<void> {
    this.onDynamicDsCreated = onDynamicDsCreated;
    const blockAmount = await this.projectService.getProcessedBlockCount();
    this.setProcessedBlockCount(blockAmount ?? 0);
  }

  onApplicationShutdown(): void {
    this.isShutdown = true;
    this.processQueue.abort();
  }

  enqueueBlocks(heights: number[]): void {
    if (!heights.length) return;

    logger.info(
      `Enqueing blocks ${heights[0]}...${last(heights)}, total ${
        heights.length
      } blocks`,
    );

    this.queue.putMany(heights);
    this.latestBufferedHeight = last(heights);

    void this.fetchBlocksFromQueue().catch((e) => {
      logger.error(e, 'Failed to fetch blocks from queue');
      if (!this.isShutdown) {
        process.exit(1);
      }
    });
  }

  flushQueue(height: number): void {
    super.flushQueue(height);
    this.processQueue.flush();
  }

  private async fetchBlocksFromQueue(): Promise<void> {
    if (this.fetching || this.isShutdown) return;
    // Process queue is full, no point in fetching more blocks
    // if (this.processQueue.freeSpace < this.nodeConfig.batchSize) return;

    this.fetching = true;

    try {
      while (!this.isShutdown) {
        const blockNums = this.queue.takeMany(
          Math.min(this.nodeConfig.batchSize, this.processQueue.freeSpace),
        );
        // Used to compare before and after as a way to check if queue was flushed
        const bufferedHeight = this._latestBufferedHeight;

        // Queue is empty
        if (!blockNums.length) {
          // The process queue might be full so no block nums were taken, wait and try again
          if (this.queue.size) {
            await delay(1);
            continue;
          }
          break;
        }

        logger.info(
          `fetch block [${blockNums[0]},${
            blockNums[blockNums.length - 1]
          }], total ${blockNums.length} blocks`,
        );

        const blocks = await this.fetchBlocksBatches(blockNums);

        if (bufferedHeight > this._latestBufferedHeight) {
          logger.debug(`Queue was reset for new DS, discarding fetched blocks`);
          continue;
        }
        const blockTasks = blocks.map((block) => async () => {
          const height = block.blockHeight;
          try {
            this.preProcessBlock(height);

            const processBlockResponse = await this.indexerManager.indexBlock(
              block,
            );

            await this.postProcessBlock(height, processBlockResponse);
          } catch (e) {
            if (this.isShutdown) {
              return;
            }
            logger.error(
              e,
              `failed to index block at height ${height} ${
                e.handler ? `${e.handler}(${e.stack ?? ''})` : ''
              }`,
            );
            throw e;
          }
        });

        // There can be enough of a delay after fetching blocks that shutdown could now be true
        if (this.isShutdown) break;

        this.processQueue.putMany(blockTasks);

        this.eventEmitter.emit(IndexerEvent.BlockQueueSize, {
          value: this.processQueue.size,
        });
      }
    } finally {
      this.fetching = false;
    }
  }
}
