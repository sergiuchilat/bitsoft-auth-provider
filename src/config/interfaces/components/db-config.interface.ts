export enum DbDriver {
  mysql = 'mysql',
  postgres = 'postgres',
  sqlite = 'sqlite',
  mssql = 'mssql',
  mongodb = 'mongodb',
}

export default interface DbConfigInterface {
  driver: DbDriver;
  host: string;
  port: number;
  user: string;
  password: string;
  name: string;
  url: string;
}
