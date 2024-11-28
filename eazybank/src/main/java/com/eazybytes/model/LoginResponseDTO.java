package com.eazybytes.model;
//* getter만 존재하고 setter가 없는 record
public record LoginResponseDTO(String status, String jwtToken) {} 