import ConfigInterface from '@/config/interfaces/app-config.interface';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

const buildApiDocs = (app, ConfigEnv: ConfigInterface['docs']) => {
  const config = new DocumentBuilder()
    .setTitle(ConfigEnv.title)
    .setDescription(ConfigEnv.description)
    .setVersion('v1.0.3-beta')
    //.addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, ConfigEnv.authName)
    // .addGlobalParameters({
    //   name: 'x-api-key',
    //   in: 'header',
    //   required: true,
    //   description: 'API Key',
    //   example: '123',
    //   schema: {
    //     type: 'string',
    //   },
    // })
    .build();
  const document = SwaggerModule.createDocument(app, config);
  console.log('document', document.components.securitySchemes);
  SwaggerModule.setup(ConfigEnv.path, app, document);
};

export default buildApiDocs;
