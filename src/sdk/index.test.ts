import { createInstance } from './index';
import { publicKey, publicKeyId, publicParams } from '../test';
import {
  bytesToHex,
  SERIALIZED_SIZE_LIMIT_CRS,
  SERIALIZED_SIZE_LIMIT_PK,
} from '../utils';

jest.mock('ethers', () => ({
  JsonRpcProvider: () => ({
    // getSigners: () => ['0x4c102C7cA99d3079fEFF08114d3bad888b9794d9'],
  }),
  isAddress: () => true,
  Contract: () => ({
    getSigners: () => ['0x4c102C7cA99d3079fEFF08114d3bad888b9794d9'],
  }),
}));

describe('index', () => {
  it('creates an instance', async () => {
    const serializedPublicKey = publicKey.safe_serialize(
      SERIALIZED_SIZE_LIMIT_PK,
    );
    const serializedPublicParams =
      publicParams[2048].publicParams.safe_serialize(SERIALIZED_SIZE_LIMIT_CRS);

    const publicParamsId = publicParams[2048].publicParamsId;
    const instance = await createInstance({
      aclContractAddress: '0x4c102C7cA99d3079fEFF08114d3bad888b9794d9',
      kmsContractAddress: '0x325ea1b59F28e9e1C51d3B5b47b7D3965CC5D8C8',
      chainId: 1234,
      publicKey: { data: serializedPublicKey, id: publicKeyId },
      publicParams: {
        2048: { publicParams: serializedPublicParams, publicParamsId },
      },
      network: 'https://network.com/',
    });
    expect(instance.createEIP712).toBeDefined();
    expect(instance.generateKeypair).toBeDefined();
    expect(instance.createEncryptedInput).toBeDefined();
    expect(instance.getPublicKey()).toStrictEqual({
      publicKey: serializedPublicKey,
      publicKeyId,
    });
    expect(instance.getPublicParams(2048)?.publicParamsId).toBe(publicParamsId);
  });

  it('fails to create an instance', async () => {
    const serializedPublicKey = publicKey.serialize();
    const serializedPublicParams =
      publicParams[2048].publicParams.safe_serialize(SERIALIZED_SIZE_LIMIT_CRS);
    const publicParamsId = publicParams[2048].publicParamsId;
    await expect(
      createInstance({
        aclContractAddress: '0x4c102C7cA99d3079fEFF08114d3bad888b9794d9',
        kmsContractAddress: '0x325ea1b59F28e9e1C51d3B5b47b7D3965CC5D8C8',
        chainId: BigInt(1234) as any,
        publicKey: { data: serializedPublicKey, id: publicKeyId },
        publicParams: {
          2048: { publicParams: serializedPublicParams, publicParamsId },
        },
        network: 'https://',
      }),
    ).rejects.toThrow('chainId must be a number');

    await expect(
      createInstance({
        aclContractAddress: '0x4c102C7cA99d3079fEFF08114d3bad888b9794d9',
        kmsContractAddress: '0x325ea1b59F28e9e1C51d3B5b47b7D3965CC5D8C8',
        chainId: 9000,
        publicKey: { data: 43 as any, id: publicKeyId },
      }),
    ).rejects.toThrow('publicKey must be a Uint8Array');
  });
});
