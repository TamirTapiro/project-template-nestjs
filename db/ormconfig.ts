import { ConfigModule } from '@nestjs/config';
import { dataSourceConfig } from '../src/config/typeorm.config';

ConfigModule.forRoot({
  isGlobal: true,
  load: [dataSourceConfig],
});

const data = dataSourceConfig();

export default data;
