import { toBufferBE } from 'bigint-buffer';
import createHash from 'keccak';

import { ENCRYPTION_TYPES } from './encryptionTypes';
import { fromHexString } from '../utils';

type EncryptionBitwidths = keyof typeof ENCRYPTION_TYPES;

const compute_handles = (
  ciphertextWithZKProof: Uint8Array,
  bitwidths: EncryptionBitwidths[],
  aclContractAddress: string,
  chainId: number,
  ciphertextVersion: number,
) => {
  // Should be identical to:
  // https://github.com/zama-ai/fhevm-backend/blob/bae00d1b0feafb63286e94acdc58dc88d9c481bf/fhevm-engine/zkproof-worker/src/verifier.rs#L301
  const blob_hash = createHash('keccak256')
    .update(Buffer.from(ciphertextWithZKProof))
    .digest();
  const aclContractAddress20Bytes = Buffer.from(
    fromHexString(aclContractAddress),
  );
  const chainId32Bytes = Buffer.from(
    new Uint8Array(toBufferBE(BigInt(chainId), 32)),
  );
  const handles = bitwidths.map((bitwidth, encryptionIndex) => {
    const encryptionType = ENCRYPTION_TYPES[bitwidth];
    const encryptionIndex1Byte = Buffer.from([encryptionIndex]);
    const handleHash = createHash('keccak256')
      .update(blob_hash)
      .update(encryptionIndex1Byte)
      .update(aclContractAddress20Bytes)
      .update(chainId32Bytes)
      .digest();
    const dataInput = new Uint8Array(32);
    dataInput.set(handleHash, 0);
    dataInput.set([encryptionIndex, encryptionType, ciphertextVersion], 29);
    return dataInput;
  });
  return handles;
};

export { compute_handles };
