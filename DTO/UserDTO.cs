using System;

namespace API.DTO;

public class UserDTO
{
    public required string UserName { get; set; }

    public required string  Token { get; set; }
}
