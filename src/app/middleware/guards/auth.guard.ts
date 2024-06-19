import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import RequestUserInterface from '@/app/request/interfaces/request-user.Interface';

@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    return this.validateRequest(request.user);
  }

  private validateRequest(user: RequestUserInterface): boolean {
    if (!user?.uuid) {
      throw new UnauthorizedException();
    }

    return true;
  }
}
