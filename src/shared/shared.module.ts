import { Module } from '@nestjs/common';
import { DatabaseModule } from './connections/database.module';

@Module({ imports: [DatabaseModule], exports: [DatabaseModule] })
export class SharedModule {}
