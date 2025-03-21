import {
  BrowserProvider,
  Contract,
  Eip1193Provider,
  JsonRpcProvider,
  Provider,
} from 'ethers';
import { PublicParams } from './encrypt';
import { getKeysFromRelayer } from './network';
import {
  fromHexString,
  cleanURL,
  SERIALIZED_SIZE_LIMIT_PK,
  SERIALIZED_SIZE_LIMIT_CRS,
} from '../utils';
import { CompactPkeCrs, TfheCompactPublicKey } from 'node-tfhe';
import { abi } from '../abi/kmsVerifier.json';

export type HTTPZInstanceConfig = {
  kmsContractAddress: string;
  aclContractAddress: string;
  chainId?: number;
  relayerUrl?: string;
  network?: Eip1193Provider | string;
  publicParams?: PublicParams<Uint8Array> | null;
  publicKey?: {
    data: Uint8Array | null;
    id: string | null;
  };
};

export const getProvider = (config: HTTPZInstanceConfig) => {
  if (typeof config.network === 'string') {
    return new JsonRpcProvider(config.network);
  } else if (config.network) {
    return new BrowserProvider(config.network);
  }
  throw new Error(
    'You must provide a network URL or a EIP1193 object (eg: window.ethereum)',
  );
};

export const getChainId = async (
  provider: Provider,
  config: HTTPZInstanceConfig,
): Promise<number> => {
  if (config.chainId && typeof config.chainId === 'number') {
    return config.chainId;
  } else if (config.chainId && typeof config.chainId !== 'number') {
    throw new Error('chainId must be a number.');
  } else {
    const chainId = (await provider.getNetwork()).chainId;
    return Number(chainId);
  }
};

export const getTfheCompactPublicKey = async (
  config: HTTPZInstanceConfig,
): Promise<{ publicKey: TfheCompactPublicKey; publicKeyId: string }> => {
  if (config.relayerUrl && !config.publicKey) {
    const inputs = await getKeysFromRelayer(cleanURL(config.relayerUrl));
    return { publicKey: inputs.publicKey, publicKeyId: inputs.publicKeyId };
  } else if (config.publicKey && config.publicKey.data && config.publicKey.id) {
    const buff = config.publicKey.data;
    try {
      return {
        publicKey: TfheCompactPublicKey.safe_deserialize(
          buff,
          SERIALIZED_SIZE_LIMIT_PK,
        ),
        publicKeyId: config.publicKey.id,
      };
    } catch (e) {
      throw new Error('Invalid public key (deserialization failed)', {
        cause: e,
      });
    }
  } else {
    throw new Error('You must provide a public key with its public key ID.');
  }
};

export const getPublicParams = async (
  config: HTTPZInstanceConfig,
): Promise<PublicParams> => {
  if (config.relayerUrl && !config.publicParams) {
    const inputs = await getKeysFromRelayer(cleanURL(config.relayerUrl));
    return inputs.publicParams;
  } else if (config.publicParams && config.publicParams['2048']) {
    const buff = config.publicParams['2048'].publicParams;
    try {
      return {
        2048: {
          publicParams: CompactPkeCrs.safe_deserialize(
            buff,
            SERIALIZED_SIZE_LIMIT_CRS,
          ),
          publicParamsId: config.publicParams['2048'].publicParamsId,
        },
      };
    } catch (e) {
      throw new Error('Invalid public key (deserialization failed)', {
        cause: e,
      });
    }
  } else {
    throw new Error('You must provide a valid CRS with its CRS ID.');
  }
};

export const getKMSSigners = async (
  provider: Provider,
  config: HTTPZInstanceConfig,
): Promise<string[]> => {
  const kmsContract = new Contract(config.kmsContractAddress, abi, provider);
  const signers: string[] = await kmsContract.getSigners();
  return signers;
};
