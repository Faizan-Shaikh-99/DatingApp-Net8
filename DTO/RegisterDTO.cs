using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

namespace API.DTO;

public class RegisterDTO
{
    [Required]
    public required string Username { get; set;}

    [Required]  
    public required string Password { get; set; }
}
