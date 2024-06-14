import { TokenType } from '@/app/modules/common/enums/token-type.enum';

export class TokenGeneratorService {
  static generatePayload (
    type: TokenType,
    sub: string,
    authProvider: string,
    user: any
  ): any{
    return  {
      props: {
        authProvider,
        type,
        email: user.email,
        name: user.name,
        photo: user.photo,
        isActive: user.isActive,
      },
      sub
    };
  }
}
