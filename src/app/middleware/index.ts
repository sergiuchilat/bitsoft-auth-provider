import { IpFilterMiddleware } from '@/app/middleware/middlewares/ip-filter.middleware';
import { ClassicAuthController } from '@/app/modules/auth/classic-auth/classic-auth.controller';
import { PassportJsController } from '@/app/modules/auth/passport-js/passport-js.controller';
import { ParseTokenMiddleware } from '@/app/middleware/middlewares/parse-token.middleware';
import {UsersController} from '@/app/modules/users/users.controller';

export default [
  {
    guard: IpFilterMiddleware,
    routes: ClassicAuthController,
  },
  {
    guard: IpFilterMiddleware,
    routes: PassportJsController,
  },
  {
    guard: ParseTokenMiddleware,
    routes: UsersController,
  },
];
