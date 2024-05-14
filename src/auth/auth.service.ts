import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from "bcrypt";
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    private readonly logger = new Logger('AuthService');

    constructor(private jwtService: JwtService) {
        super();
    }

    async onModuleInit() {
        await this.$connect();
        this.logger.log("Database mongo db connected")

    }

    async registerUser(registerUserDto: RegisterUserDto) {

        const { email, name, password } = registerUserDto;

        const user = await this.user.findFirst({
            where: { email: email }
        });

        if (user) {
            throw new RpcException({
                status: HttpStatus.BAD_REQUEST,
                message: "User already exists"
            })

        }

        const newUser = await this.user.create({
            data: {
                email, name,
                password: bcrypt.hashSync(password, 10)
            }
        });

        const { password: __, ...rest } = newUser;
        const token = await this.getToken(user.name, email, user.id);

        return {
            user: rest,
            token
        }

    }


    async loginUser(loginUserDto: LoginUserDto) {
        const { email, password } = loginUserDto;
        const user = await this.user.findFirst({
            where: { email }

        })

        if (!user) throw new RpcException({ status: HttpStatus.NOT_FOUND, message: "Email or password it is invalid" });

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) throw new RpcException({ status: HttpStatus.BAD_REQUEST, message: "Email or password it is invalid" });
        const { password: __, ...rest } = user;
        const token = await this.getToken(user.name, email, user.id);
        return {
            user: rest,
            token
        }


    }


    async verifyUser(token: string) {
        try {
            const {iat,exp,...user} = await this.jwtService.verifyAsync(token,
                {
                    secret: envs.keySecret
                }
            );
            return {
                user,token: await this.getToken(user.name,user.email,user.id)
            };
        } catch (error) {
            console.log(error);
            throw new RpcException({status: HttpStatus.UNAUTHORIZED, message:"Invalid token"})
        }
      
    }


    async getToken(name: string, email: string, id) {
        return await this.jwtService.signAsync({ name, email, id })
    }

}
