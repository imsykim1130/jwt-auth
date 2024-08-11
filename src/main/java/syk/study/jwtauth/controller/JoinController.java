package syk.study.jwtauth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import syk.study.jwtauth.dto.JoinDto;
import syk.study.jwtauth.service.JoinService;

@RestController
@RequiredArgsConstructor
public class JoinController {
    private final JoinService joinService;

    @PostMapping("/join")
    public String join(@RequestBody JoinDto joinDto) {
        joinService.joinProcess(joinDto);
        return "join";
    }
}
