import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async hashPassword(password: string) {
    return bcrypt.hash(password, 10);
  }

  async signPayload(userId: number, email: string): Promise<Tokens> {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        { expiresIn: process.env.JWT_TIMEOUT, secret: process.env.JWT_SECRET },
      ),
      this.jwtService.signAsync(
        { sub: userId, email },
        {
          secret: process.env.JWT_REFRESH_SECRET,
          expiresIn: process.env.JWT_REFRESH_TIMEOUT,
        },
      ),
    ]);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }
  async localSignup(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashPassword(dto.password);
    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
        updatedAt: new Date(),
      },
    });
    const tokens = await this.signPayload(newUser.id, newUser.email);
    await this.saveRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async localSignin(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new UnauthorizedException('Access denied');
    const passwordMatch = await bcrypt.compare(dto.password, user.hash);

    if (!passwordMatch) throw new UnauthorizedException('Access denied');

    const tokens = await this.signPayload(user.id, user.email);
    await this.saveRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: number) {
    await this.prisma.user.update({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  async tokensRefresh(userId: number, refreshToken: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user || !user.hashedRt)
      throw new UnauthorizedException('Access denied');
    const rt = refreshToken.replace('Bearer', '').trim();

    const refreshTokenMatch = await bcrypt.compare(rt, user.hashedRt);

    if (!refreshTokenMatch) throw new UnauthorizedException('Access denied');

    const tokens = await this.signPayload(user.id, user.email);
    await this.saveRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async saveRtHash(userId: number, refreshToken: string) {
    const hash = await this.hashPassword(refreshToken);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }
}
