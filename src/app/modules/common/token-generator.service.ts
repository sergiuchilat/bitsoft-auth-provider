export class TokenGeneratorService {
  static generatePayload (sub: string, authProvider: string, user: any): any{
    return  {
      props: {
        authProvider,
        email: user.email,
        name: user.name,
        photo: user.photo,
        isActive: user.isActive,
        domain: user.domain
      },
      sub
    };
  }
}
