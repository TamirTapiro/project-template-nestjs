// auth.controller.ts
import {
  Controller,
  Post,
  Body,
  Get,
  Param,
  Put,
  BadRequestException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from 'src/shared/decorator/public';
import { ApiTags } from '@nestjs/swagger';
import {
  ChangePasswordDto,
  LoginDto,
  RefreshTokenDto,
  ResetPasswordDto,
  SendMailDto,
} from './auth.dto';
import { CreateUserDto } from 'src/modules/user/dto/create-user.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  async register(@Body() createUserDto: CreateUserDto) {
    const user = await this.authService.register(createUserDto);
    if (user) {
      return await this.authService.createEmailTokenAndSendMail(
        createUserDto.email,
      );
    } else {
      throw new BadRequestException('Something went wrong while register user');
    }
  }

  @Public()
  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    const user = await this.authService.validateUser(
      loginDto.email,
      loginDto.password,
    );
    return this.authService.login(user);
  }

  @Public()
  @Post('resend-verification-email')
  async sendVerificationEmail(@Body() body: SendMailDto) {
    return await this.authService.createEmailTokenAndSendMail(body.email);
  }

  @Public()
  @Get('email-verify/:token')
  async verifyToken(@Param('token') token: string) {
    return await this.authService.verifyEmail(token);
  }

  @Public()
  @Post('forgot-password')
  async forgotPassword(@Body() body: SendMailDto) {
    return await this.authService.createForgotPasswordTokenAndSendMail(
      body.email,
    );
  }

  @Public()
  @Post('reset-password/:token')
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Param('token') token: string,
  ) {
    return await this.authService.resetPassword(resetPasswordDto, token);
  }

  @Public()
  @Post('refresh-token')
  async refreshToken(@Body() body: RefreshTokenDto) {
    return this.authService.refreshToken(body.refreshToken);
  }

  @Put('change-password')
  async changePassword(
    @Param(':id') id: number,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    return this.authService.changePassword(id, changePasswordDto);
  }
}
