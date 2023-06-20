import sodium, { KeyPair } from 'libsodium-wrappers';
import { bytesToNumber, fromHexString } from '../utils';

export const decrypt = async (keypair: KeyPair, ciphertext: string | Uint8Array): Promise<number> => {
  await sodium.ready;
  const toDecrypt = typeof ciphertext === 'string' ? fromHexString(ciphertext) : ciphertext;

  const decrypted = sodium.crypto_box_seal_open(toDecrypt, keypair.publicKey, keypair.privateKey);
  return bytesToNumber(decrypted);
};
