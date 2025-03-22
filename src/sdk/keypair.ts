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
  message: {
    publicKey: string;
    contractAddresses: string[];
    contractsChainId: number;
    startTimestamp: string;
    durationDays: number;
    delegatedAccount?: string;
  };
  primaryType: string;
  types: {
    [key: string]: EIP712Type[];
  };
};

export const createEIP712 =
  (chainId: number) =>
  (
    publicKey: string,
    verifyingContract: string,
    contractAddresses: string[],
    contractsChainId: number,
    startTimestamp: string,
    durationDays: number,
    delegatedAccount?: string,
  ) => {
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
        UserDecryptRequestVerification: [
          { name: 'publicKey', type: 'bytes' },
          { name: 'contractAddresses', type: 'address[]' },
          { name: 'contractsChainId', type: 'uint256' },
          { name: 'startTimestamp', type: 'uint256' },
          { name: 'durationDays', type: 'uint256' },
        ],
      },
      // This defines the message you're proposing the user to sign, is dapp-specific, and contains
      // anything you want. There are no required fields. Be as explicit as possible when building out
      // the message schema.
      // This refers to the keys of the following types object.
      primaryType: 'UserDecryptRequestVerification',
      domain: {
        // Give a user-friendly name to the specific contract you're signing for.
        name: 'DecryptionManager',
        // This identifies the latest version.
        version: '1',
        // This defines the network, in this case, Mainnet.
        chainId: 654321,
        // // Add a verifying contract to make sure you're establishing contracts with the proper entity.
        verifyingContract,
      },
      message: {
        publicKey: publicKey,
        contractAddresses: contractAddresses,
        contractsChainId: 123456,
        startTimestamp: startTimestamp,
        durationDays: durationDays,
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

export const generateKeypair = () => {
  const keypair = cryptobox_keygen();
  return {
    publicKey: toHexString(cryptobox_pk_to_u8vec(cryptobox_get_pk(keypair))),
    privateKey: toHexString(cryptobox_sk_to_u8vec(keypair)),
  };
};
