import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import RequestUserInterface from '@/app/request/interfaces/request-user.Interface';
import AppConfig from '@/config/app-config';
import { Language } from '@/app/enum/language.enum';
import { I18nService } from 'nestjs-i18n';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly i18nService: I18nService) {}
  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    return this.validateRequest(request.user, request.hostname, request.localization);
  }

  private validateRequest(user: RequestUserInterface, host: string, language: Language): boolean {
    if (!user?.uuid) {
      throw new UnauthorizedException();
    }

    const isCrossDomainToken = AppConfig.app.cross_domain_token === 1;

    if (isCrossDomainToken) {
      const requestDomain = this.getRequestDomain(user);

      if (!this.isSubdomainOf(host, requestDomain)) {
        throw new UnauthorizedException(
          this.i18nService.t('auth.errors.token_domain_mismatch', {
            lang: language,
          }),
        );
      }
    }

    return true;
  }

  private getRequestDomain(user: RequestUserInterface): string {
    const host = user.domain;

    if (!host) {
      throw new UnauthorizedException('Host header is missing');
    }
    return host.split(':')[0];
  }

  private isSubdomainOf(domain: string, requestDomain: string): boolean {
    return requestDomain === domain || requestDomain.endsWith(`.${domain}`);
  }
}
