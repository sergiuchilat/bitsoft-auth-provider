import { Injectable, NestMiddleware } from '@nestjs/common';

import { NextFunction, Request, Response } from 'express';
import { Language } from '@/app/enum/language.enum';
import { setLanguage } from '@/app/utils/localization';

@Injectable()
export class ParseLocalizationMiddleware implements NestMiddleware {
  async use(req: Request, res: Response, next: NextFunction) {
    //console.log('ParseLocalizationMiddleware')
    try {
      const localization = req.headers['x-localization']?.toString()?.toLowerCase() || Language.en;
      req.localization = setLanguage(localization as Language);
    } catch (e) {
      console.log(e);
      req.localization = Language.en;
    } finally {
      next();
    }
  }
}
