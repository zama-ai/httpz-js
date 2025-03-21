import { isAddress } from 'ethers';
import { toHexString } from '../utils';
import {
  cryptobox_keygen,
  cryptobox_sk_to_u8vec,
  cryptobox_pk_to_u8vec,
  cryptobox_get_pk,
} from 'node-tkms';

export type EIP712Type = { name: string; type: string };

export type EIP712 = {
  domain: {
    chainId: number;
    name: string;
    verifyingContract: string;
    version: string;
  };
  message: any;
  primaryType: string;
  types: {
    [key: string]: EIP712Type[];
  };
};

export const createEIP712 =
  (chainId: number) =>
  (publicKey: string, verifyingContract: string, delegatedAccount?: string) => {
    if (!isAddress(verifyingContract))
      throw new Error('Invalid contract address.');
    if (delegatedAccount && !isAddress(delegatedAccount))
      throw new Error('Invalid delegated account.');
    const msgParams: EIP712 = {
      types: {
        // This refers to the domain the contract is hosted on.
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        // Refer to primaryType.
        Reencrypt: [{ name: 'publicKey', type: 'bytes' }],
      },
      // This defines the message you're proposing the user to sign, is dapp-specific, and contains
      // anything you want. There are no required fields. Be as explicit as possible when building out
      // the message schema.
      // This refers to the keys of the following types object.
      primaryType: 'Reencrypt',
      domain: {
        // Give a user-friendly name to the specific contract you're signing for.
        name: 'Authorization token',
        // This identifies the latest version.
        version: '1',
        // This defines the network, in this case, Mainnet.
        chainId,
        // // Add a verifying contract to make sure you're establishing contracts with the proper entity.
        verifyingContract,
      },
      message: {
        publicKey: `0x${publicKey}`,
      },
    };

    if (delegatedAccount) {
      msgParams.message.delegatedAccount = delegatedAccount;
      msgParams.types.Reencrypt.push({
        name: 'delegatedAccount',
        type: 'address',
      });
    }
    return msgParams;
  };

/**
 * Creates an EIP712 structure specifically for user decrypt requests
 *
 * @param gatewayChainId The chain ID of the gateway
 * @param verifyingContract The address of the contract that will verify the signature
 * @param publicKey The user's public key as a hex string or Uint8Array
 * @param contractAddresses Array of contract addresses that can access the decryption
 * @param contractsChainId The chain ID where the contracts are deployed
 * @param startTimestamp The timestamp when the decryption permission becomes valid
 * @param durationDays How many days the decryption permission remains valid
 * @returns EIP712 typed data structure for user decryption
 */
export const createEIP712UserDecrypt = (
  gatewayChainId: number,
  verifyingContract: string,
  publicKey: string | Uint8Array,
  contractAddresses: string[],
  contractsChainId: string | number,
  startTimestamp: bigint | string,
  durationDays: bigint | string,
): EIP712 => {
  if (!isAddress(verifyingContract)) {
    throw new Error('Invalid verifying contract address.');
  }

  // Format the public key based on its type
  const formattedPublicKey =
    typeof publicKey === 'string'
      ? publicKey.startsWith('0x')
        ? publicKey
        : `0x${publicKey}`
      : publicKey;

  // Convert timestamps to strings if they're bigints
  const formattedStartTimestamp =
    typeof startTimestamp === 'bigint'
      ? startTimestamp.toString()
      : startTimestamp;

  const formattedDurationDays =
    typeof durationDays === 'bigint' ? durationDays.toString() : durationDays;

  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      UserDecryptRequestVerification: [
        { name: 'publicKey', type: 'bytes' },
        { name: 'contractAddresses', type: 'address[]' },
        { name: 'contractsChainId', type: 'uint256' },
        { name: 'startTimestamp', type: 'uint256' },
        { name: 'durationDays', type: 'uint256' },
      ],
    },
    primaryType: 'EIP712UserDecryptRequest',
    domain: {
      name: 'DecryptionManager',
      version: '1',
      chainId: gatewayChainId,
      verifyingContract,
    },
    message: {
      publicKey: formattedPublicKey,
      contractAddresses,
      contractsChainId,
      startTimestamp: formattedStartTimestamp,
      durationDays: formattedDurationDays,
    },
  };
};

export const generateKeypair = () => {
  const keypair = cryptobox_keygen();
  return {
    publicKey: toHexString(cryptobox_pk_to_u8vec(cryptobox_get_pk(keypair))),
    privateKey: toHexString(cryptobox_sk_to_u8vec(keypair)),
  };
};
