// Copyright 2020-2022 OnFinality Limited authors & contributors
// SPDX-License-Identifier: Apache-2.0

import { AvalancheApi } from './api.avalanche';

describe('Avalanche api', () => {
  it('Can get a block with expected data', async () => {
    const api = new AvalancheApi({
      endpoint: 'https://avalanche.api.onfinality.io/public',
      subnet: 'C',
      chainId: 'C',
    });

    const block = await api.fetchBlock(90);

    expect(block.block.extraData).toBe(
      '0xda83010916846765746888676f312e31342e328777696e646f777322b7b3dd850a436efcd6e2e27559f0333201554ef5354389428a68994d83fa4a',
    );
  });
});
