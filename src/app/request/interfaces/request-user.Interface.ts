export default interface RequestUserInterface {
  uuid: string;
  domain: string;
  email: string;
  isTwoFactorEnable: boolean;
  isTwoFactorConfirmed: boolean;
}
