using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTO;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController(DataContext context, ITokenService tokenService) : BaseApiController
    {
    
        [HttpPost("register")]
        public async Task<ActionResult<UserDTO>> Register(RegisterDTO registerDTO){

            if(await UserExists(registerDTO.Username)) return BadRequest("User already exists");

            using var hmac = new HMACSHA512();

            var user = new AppUser 
            {
                UserName = registerDTO.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
                PasswordSalt = hmac.Key
            };
            
            context.Users.Add(user);
            await context.SaveChangesAsync();
            
            return new UserDTO{
                USerName = user.UserName,
                Token = tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDTO>> Login(LoginDTO loginDTO){

            var user = await context.Users.FirstOrDefaultAsync(x => x.UserName == loginDTO.Username.ToLower());

            if(user == null) return Unauthorized("Invalid UserName");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDTO.Password));

            for(var i = 0; i < computedHash.Length; i++){

                if(computedHash[i] != loginDTO.Password[i]) return Unauthorized("Invalid PassWord");

            }

            return new UserDTO{
                USerName = user.UserName,
                Token = tokenService.CreateToken(user)
            };
        }

        private async Task<bool> UserExists(string username){

            return await context.Users.AnyAsync(x => x.UserName.ToLower() == username.ToLower());

        }
    }
}
