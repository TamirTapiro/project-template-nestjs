import { NestFactory } from '@nestjs/core';
import {
  SwaggerModule,
  DocumentBuilder,
  SwaggerDocumentOptions,
} from '@nestjs/swagger';
import { AppModule } from './app.module';
import * as path from 'path';
import { writeFileSync } from 'fs';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe());

  const config = new DocumentBuilder()
    .setTitle('Template project')
    .setDescription('Template project API description')
    .setVersion('1.0')
    .addTag('template')
    .addTag('example')
    .addTag('draft')
    .addTag('senior')
    .build();
  const options: SwaggerDocumentOptions = {
    operationIdFactory: (controllerKey: string, methodKey: string) => methodKey,
    deepScanRoutes: true,
  };
  const document = SwaggerModule.createDocument(app, config, options);
  const outputPath = path.resolve(process.cwd(), 'swagger.json');
  writeFileSync(outputPath, JSON.stringify(document), { encoding: 'utf8' });

  SwaggerModule.setup('api', app, document);
  await app.listen(3000);
}
bootstrap();
