import { Injectable } from '@nestjs/common';
import fs from 'node:fs';
import parse from 'node-html-parser';
import { HttpService } from '@nestjs/axios';

@Injectable()
export class MailerService {
  private readonly notifyServiceUrl = process.env.NOTIFY_SERVICE_URL;
  private readonly notifyServiceApiKey = process.env.NOTIFY_SERVICE_KEY;

  async sendActivationEmail(email: string, activationLink: string, name = '') {
    const notifyServiceTemplate = 'registration-confirmation';
    const templateData = fs.readFileSync(`src/data/email-templates/${notifyServiceTemplate}/en.html`, 'utf8');

    const emailBody = templateData
      .replaceAll('{PROJECT_NAME}', process.env.PROJECT_NAME)
      .replaceAll('{LOGO_URL}', process.env.PROJECT_LOGO_URL)
      .replaceAll('{USER_FULL_NAME}', name)
      .replaceAll('{CONFIRM_LINK}', activationLink)
      .replaceAll('{PROJECT_URL}', process.env.PROJECT_URL);

    return await this.sendNotifyOnEmail(email, emailBody);
  }

  constructor(private readonly httpService: HttpService) {}

  async sendResetPasswordEmail(email: string, name = '', resetPasswordLink: string) {
    const notifyServiceTemplate = 'password-reset';
    const templateData = fs.readFileSync(`src/data/email-templates/${notifyServiceTemplate}/en.html`, 'utf8');

    const emailBody = templateData
      .replaceAll('{PROJECT_NAME}', process.env.PROJECT_NAME)
      .replaceAll('{LOGO_URL}', process.env.PROJECT_LOGO_URL)
      .replaceAll('{USER_FULL_NAME}', name)
      .replaceAll('{RESET_PASSWORD_LINK}', resetPasswordLink)
      .replaceAll('{PROJECT_URL}', process.env.PROJECT_URL);

    return await this.sendNotifyOnEmail(email, emailBody);
  }

  private async sendNotifyOnEmail(email: string, emailBody: string) {
    try {
      const notifySendUrl = `${this.notifyServiceUrl}`;
      await this.httpService.axiosRef
        .post(
          notifySendUrl,
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
        )
        .then((response) => {
          console.log('response', response.data);
          return response.data;
        })
        .catch((error) => {
          console.error('error', error);
          return error;
        });

      console.log('Email sent to', email);
    } catch (e) {
      console.error(e);
    }

    return emailBody;
  }
}
