import { Body, Controller, Post } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthDto, AuthSignDto } from "./dto";

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('signin')
    async signin(@Body() dto: AuthSignDto) {
        return this.authService.signin(dto);

    }
    @Post('signup')
    async signup(@Body() dto: AuthDto) {
        return this.authService.signup(dto);
    }
}