import { OauthProvider } from '@/app/modules/common/enums/provider.enum';

export default interface RequestUserInterface {
  uuid: string;
  domain: string;
  email: string;
  isTwoFactorEnable: boolean;
  isTwoFactorConfirmed: boolean;
  authProvider: OauthProvider;
}
