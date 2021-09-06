using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _contex;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext contex, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _contex = contex;
        }
        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            if (await UserExists(registerDto.Username)) return BadRequest("Username is taken");
            using (var hmac = new HMACSHA512())
            {
                var user = new AppUser
                {
                    UserName = registerDto.Username,
                    PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                    PasswordSalt = hmac.Key
                };
                _contex.Users.Add(user);
                await _contex.SaveChangesAsync();

                return new UserDto
                {
                    Username = user.UserName,
                    Token = _tokenService.CreateToken(user)
                };
            }
        }
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _contex.Users.
            SingleOrDefaultAsync(x => x.UserName == loginDto.Username);

            if (user == null) return Unauthorized("Invalid username");

            using (var hmac = new HMACSHA512(user.PasswordSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
                for (int x = 0; x < computedHash.Length; x++)
                {
                    if (user.PasswordHash[x] != computedHash[x]) return Unauthorized("Invalid Password");
                }
            }

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }
        private async Task<bool> UserExists(string Username)
        {
            return await _contex.Users.AnyAsync(x => x.UserName == Username.ToLower());
        }
    }
}
