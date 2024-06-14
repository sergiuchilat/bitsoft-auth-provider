import { IpFilterMiddleware } from '@/app/middleware/middlewares/ip-filter.middleware';
import { ClassicAuthController } from '@/app/modules/auth/classic-auth/classic-auth.controller';
import { PassportJsController } from '@/app/modules/auth/passport-js/passport-js.controller';
import { ParseTokenMiddleware } from '@/app/middleware/middlewares/parse-token.middleware';
import { ParseLocalizationMiddleware } from '@/app/middleware/middlewares/parse-localization.middleware';

export default [
  {
    guard: ParseTokenMiddleware,
    routes: ClassicAuthController,
  },
  {
    guard: ParseLocalizationMiddleware,
    routes: '*',
  },
  {
    guard: ParseTokenMiddleware,
    routes: PassportJsController,
  },
  {
    guard: IpFilterMiddleware,
    routes: ClassicAuthController,
  },
  {
    guard: IpFilterMiddleware,
    routes: PassportJsController,
  },
];
