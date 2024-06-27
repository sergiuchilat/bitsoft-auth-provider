import { Injectable, Logger } from '@nestjs/common';
import fs from 'node:fs';
import parse from 'node-html-parser';
import { HttpService } from '@nestjs/axios';
import { Language } from '@/app/enum/language.enum';

@Injectable()
export class MailerService {
  private readonly notifyServiceUrl = process.env.NOTIFY_SERVICE_URL;
  private readonly notifyServiceApiKey = process.env.NOTIFY_SERVICE_KEY;
  private readonly logger = new Logger('Mailer');

  constructor(private readonly httpService: HttpService) {}

  public sendActivationEmail(email: string, activationLink: string, name = '', language: Language) {
    const notifyServiceTemplate = 'registration-confirmation';
    const templateData = fs.readFileSync(
      `src/data/email-templates/${notifyServiceTemplate}/${language || 'en'}.html`,
      'utf8',
    );

    const emailBody = templateData
      .replaceAll('{PROJECT_NAME}', process.env.PROJECT_NAME)
      .replaceAll('{LOGO_URL}', process.env.PROJECT_LOGO_URL)
      .replaceAll('{USER_FULL_NAME}', name)
      .replaceAll('{CONFIRM_LINK}', activationLink)
      .replaceAll('{PROJECT_URL}', process.env.PROJECT_URL);

    return this.sendNotificationOnEmail(email, emailBody);
  }

  public sendResetPasswordEmail(email: string, name = '', resetPasswordLink: string) {
    const notifyServiceTemplate = 'password-reset';
    const templateData = fs.readFileSync(`src/data/email-templates/${notifyServiceTemplate}/en.html`, 'utf8');

    const emailBody = templateData
      .replaceAll('{PROJECT_NAME}', process.env.PROJECT_NAME)
      .replaceAll('{LOGO_URL}', process.env.PROJECT_LOGO_URL)
      .replaceAll('{USER_FULL_NAME}', name)
      .replaceAll('{RESET_PASSWORD_LINK}', resetPasswordLink)
      .replaceAll('{PROJECT_URL}', process.env.PROJECT_URL);

    return this.sendNotificationOnEmail(email, emailBody);
  }

  private async sendNotificationOnEmail(email: string, emailBody: string) {
    try {
      await this.httpService.axiosRef.post(
        this.notifyServiceUrl,
        {
          subject: parse(emailBody).querySelector('title').text,
          body: parse(emailBody).querySelector('body').innerHTML,
          language: 'en',
          receivers: [email],
        },
        {
          headers: {
            'x-api-key': `${this.notifyServiceApiKey}`,
          },
        },
      );

      this.logger.log('Email sent to', email);
    } catch (e) {
      this.logger.log(e);
    }

    return emailBody;
  }
}
