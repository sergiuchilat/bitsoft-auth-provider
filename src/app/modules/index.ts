import { UsersModule } from '@/app/modules/users/users.module';
import { PassportJsModule } from '@/app/modules/auth/passport-js/passport-js.module';
import { ClassicAuthModule } from '@/app/modules/auth/classic-auth/classic-auth.module';
import { BlockedIpModule } from '@/app/modules/blocked-ip/blocked-ip.module';
import { AuthLogModule } from '@/app/modules/auth-log/auth-log.module';

export default [UsersModule, ClassicAuthModule, PassportJsModule, BlockedIpModule, AuthLogModule];
