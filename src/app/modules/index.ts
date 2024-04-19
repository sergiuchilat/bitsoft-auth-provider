import { ClassicAuthModule } from '@/app/modules/auth/classic-auth/classic-auth.module';
import { GoogleAuthModule } from '@/app/modules/auth/google-auth/google-auth.module';
import { VkAuthModule } from '@/app/modules/auth/vk-auth/vk-auth.module';

export default [
  ClassicAuthModule,
  GoogleAuthModule,
  VkAuthModule
];
