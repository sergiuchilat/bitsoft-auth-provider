export default interface JwtConfigInterface {
  secret: string;
  expiresIn: number;
  refreshTokenExpiresIn: number;
  privateKeyPath: string;
  privateKey: string;
  publicKeyPath: string;
  publicKey: string;
}
