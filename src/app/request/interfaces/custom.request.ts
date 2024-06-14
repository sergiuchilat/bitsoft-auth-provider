import { Language } from '@/app/enum/language.enum';

declare module 'express-serve-static-core' {
  interface Request {
    localization?: Language;
  }
}
