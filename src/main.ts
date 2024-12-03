import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as firebaseAdmin from 'firebase-admin';
import * as fs from 'fs';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors();
  const config = new DocumentBuilder()
    .setTitle('Authentication')
    .setDescription(
      'The API details for the Authentication Demo application using Firebase in the NestJS backend.',
    )
    .setVersion('1.0')
    .addTag('Authentication')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  //firebase ;
  const firebaseKeyFilePath =
    './user-authentication-94ddb-firebase-adminsdk-fym5l-92e09dab17.json';
  const firebaseServiceAccount /*: ServiceAccount*/ = JSON.parse(
    fs.readFileSync(firebaseKeyFilePath).toString(),
  );
  if (firebaseAdmin.apps.length === 0) {
    console.log('Initialize Firebase Application.');
    firebaseAdmin.initializeApp({
      credential: firebaseAdmin.credential.cert(firebaseServiceAccount),
    });
  }

  await app.listen(process.env.PORT);
}
bootstrap();
