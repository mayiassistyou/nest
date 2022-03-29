import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

import { PrismaService } from 'src/prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: SignupDto) {
    try {
      // hash the password
      const hash = await argon.hash(dto.password);

      //save the new user in db
      const { password, ...rest } = dto;

      const user = await this.prisma.user.create({
        data: {
          ...rest,
          hash,
        },
      });

      delete user.hash;

      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if ((error.code = 'P2002')) {
          throw new HttpException('User already exist!!!', HttpStatus.CONFLICT);
        }
      }

      throw error;
    }
  }

  async signin(dto: SigninDto) {
    // find user in db
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // if user does not exist throw exception
    if (!user)
      throw new HttpException(
        'Wrong email or password!!!',
        HttpStatus.UNAUTHORIZED,
      );

    //compare password
    const matchedPassword = await argon.verify(user.hash, dto.password);
    if (!matchedPassword)
      throw new HttpException(
        'Wrong email or password!!!',
        HttpStatus.UNAUTHORIZED,
      );

    delete user.hash;

    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '24h',
      secret,
    });

    return {
      access_token: token,
    };
  }
}
