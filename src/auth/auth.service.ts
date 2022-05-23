import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto, AuthSignDto } from "./dto";
import * as argon from 'argon2'
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
@Injectable({})
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) {
    }
    async signup(dto: AuthDto) {
        const hash = await argon.hash(dto.password);
        const user = await this.prisma.user.create({
            data: {
                firstName: dto.firstName,
                lastName: dto.lastName,
                email: dto.email,
                hash 
            }
        })
        delete user.hash;

        return user
    }

    async signin(dto: AuthSignDto) {
        const user = await this.prisma.user.findUnique({
            where : {
                email: dto.email
            }
        })
        
        if (!user) {
            throw new ForbiddenException("credentials not find");
        }

        const PwMatches = await argon.verify(user.hash, dto.password);
        if (!PwMatches) {
            throw new ForbiddenException("credentials not find");

        }
        delete user.hash

        return this.signinToken(user.id,user.email); 
    }
   
     async signinToken(userId: Number, userEmail: String): Promise <{ access_token: string } >{
        const payload = {
            sub: userId,
            userEmail
        }
        const secret = this.config.get("JWT_SECRET")
        const token =  await this.jwt.signAsync(payload, {
            expiresIn: "10h",
            secret: secret
        })
        
        return {access_token : token};
        
    }

}