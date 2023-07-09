import { KeyLike, importJWK } from 'jose'

export const getKey = async (data: any): Promise<KeyLike> => {
  return data.kty ? importJWK(data) : data;
};