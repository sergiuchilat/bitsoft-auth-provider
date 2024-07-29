import AppConfigInterface from '../interfaces/app-config.interface';
import { DbDriver } from '../interfaces/components/db-config.interface';
import { generateDatabaseUrl } from '@/config/services/db.service';
import * as dotenv from 'dotenv';
import * as fs from 'fs';
import * as process from 'node:process';

dotenv.config();

export default class EnvConfigStrategy {
  private readonly config: AppConfigInterface = null;

  constructor() {
    //console.log('process ENV', process.env);
    let JWT_PUBLIC_KEY = null;
    let JWT_PRIVATE_KEY = null;
    try {
      JWT_PUBLIC_KEY =
        process.env.JWT_PUBLIC_KEY ?? fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH ?? '', 'utf8');
      JWT_PRIVATE_KEY =
        process.env.JWT_PRIVATE_KEY ?? fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH ?? '', 'utf8');
    } catch (e) {
      console.log('Error reading JWT_PUBLIC_KEY_PATH', e.message);
    }

    this.config = {
      app: {
        port: process.env.APP_PORT,
        requestTimeout: Number(process.env.APP_REQUEST_TIMEOUT),
        security: {
          write_access_key: process.env.APP_SECURITY_ACCESS_KEY,
        },
        session: {
          secret: process.env.SESSION_SECRET,
        },
        cross_domain_token: Number(process.env.CROSS_DOMAIN_TOKEN),
        app_two_fa_connected: Number(process.env.APP_TWO_FA_CONNECTED),
        log: {
          custom: process.env.APP_LOG_CUSTOM === 'true',
          levels: {
            error: {
              filename: process.env.APP_LOG_ERROR_FILENAME,
              maxFiles: process.env.APP_LOG_ERROR_MAX_FILES,
            },
            all: {
              filename: process.env.APP_LOG_ALL_FILENAME,
              maxFiles: process.env.APP_LOG_ALL_MAX_FILES,
            },
          },
        },
      },
      authProviders: {
        classic: {
          code_expires_in: Number(process.env.CLASSIC_AUTH_CODE_EXPIRES_IN),
        },
        google: {
          clientId: process.env.GOOGLE_AUTH_CLIENT_ID,
          clientSecret: process.env.GOOGLE_AUTH_CLIENT_SECRET,
          redirectURL: process.env.GOOGLE_AUTH_REDIRECT_URL,
        },
        vk: {
          clientId: process.env.VK_AUTH_CLIENT_ID,
          accessToken: process.env.VK_AUTH_ACCESS_TOKEN,
          serviceToken: process.env.VK_AUTH_SERVICE_TOKEN,
          redirectURL: process.env.VK_AUTH_REDIRECT_URL,
        },
      },
      db: {
        host: process.env.DB_HOST,
        port: parseInt(process.env.DB_PORT),
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        name: process.env.DB_NAME,
        driver: DbDriver[process.env.DB_DRIVER],
        url: null,
      },
      jwt: {
        secret: process.env.JWT_SECRET_KEY,
        twoFaSecret: process.env.JWT_PUBLIC_TWO_FA_SECRET,
        expiresIn: Number(process.env.JWT_TOKEN_EXPIRES_IN),
        refreshTokenExpiresIn: Number(process.env.JWT_REFRESH_TOKEN_EXPIRES_IN),
        publicKeyPath: process.env.JWT_PUBLIC_KEY_PATH,
        publicKey: JWT_PUBLIC_KEY,
        privateKeyPath: process.env.JWT_PRIVATE_KEY_PATH,
        privateKey: JWT_PRIVATE_KEY,
      },
      docs: {
        generate: process.env.DOCS_GENERATE === 'true',
        path: process.env.DOCS_PATH,
        version: process.env.DOCS_VERSION,
        title: process.env.DOCS_TITLE,
        description: process.env.DOCS_DESCRIPTION,
        authName: process.env.DOCS_AUTH_NAME,
      },
      telegram: {
        botName: process.env.TELEGRAM_BOT_NAME,
        botToken: process.env.TELEGRAM_BOT_TOKEN,
      },
      mail: {
        mailer: process.env.MAIL_MAILER,
        host: process.env.MAIL_HOST,
        port: Number(process.env.MAIL_PORT),
        username: process.env.MAIL_USERNAME,
        password: process.env.MAIL_PASSWORD,
        encryption: process.env.MAIL_ENCRYPTION,
        fromAddress: process.env.MAIL_FROM_ADDRESS,
        fromName: process.env.MAIL_FROM_NAME,
        retryAttempts: Number(process.env.MAIL_RETRY_ATTEMPTS),
        cronTimeout: process.env.MAIL_CRON_TIMEOUT,
      },
    };

    this.config.db.url = generateDatabaseUrl(this.config.db);
  }

  public getConfig() {
    return this.config;
  }
}
