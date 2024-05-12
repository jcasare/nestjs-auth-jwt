import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { RereshTokenGuard } from 'src/common/guards';
import {
  GetCurrentUser,
  GetCurrentUserId,
  isPublic,
} from 'src/common/decorators';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @isPublic()
  @Post('/local/signup')
  localSignup(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.localSignup(dto);
  }

  @isPublic()
  @Post('/local/signin')
  @HttpCode(HttpStatus.OK)
  localSignin(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.localSignin(dto);
  }

  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUserId() userId: number) {
    return this.authService.logout(userId);
  }

  @isPublic()
  @UseGuards(RereshTokenGuard)
  @Post('/refresh')
  @HttpCode(HttpStatus.OK)
  tokensRefresh(
    @GetCurrentUser('refreshToken') refreshToken: string,
    @GetCurrentUserId() userId: number,
  ) {
    return this.authService.tokensRefresh(userId, refreshToken);
  }
}
