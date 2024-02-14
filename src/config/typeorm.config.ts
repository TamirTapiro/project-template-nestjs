import { registerAs } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

const dataSourceConfig = registerAs('dataSourceConfig', () => {
  return new DataSource({
    type: 'mysql',
    logging: false,
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT!),
    username: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    entities: ['src/**/*.entity{.js,.ts}'],
    migrations: ['db/migrations/*{.ts,.js}'],
  });
});

const typeOrmModuleConfig = registerAs(
  'typeOrmModuleConfig',
  (): TypeOrmModuleOptions => {
    return {
      type: 'mysql',
      logging: false,
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT!),
      username: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      entities: ['dist/src/**/*.entity{.js,.ts}'],
      migrations: ['dist/db/migrations/*{.ts,.js}'],
    };
  },
);

export { dataSourceConfig, typeOrmModuleConfig };
