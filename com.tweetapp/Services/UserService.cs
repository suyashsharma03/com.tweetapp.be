using AutoMapper;
using com.tweetapp.Data.IRepository;
using com.tweetapp.Models;
using com.tweetapp.Models.Dtos.UserDto;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace com.tweetapp.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _user;
        private readonly IMapper _mapper;
        private readonly IConfiguration _config;
        static readonly log4net.ILog _log4net = log4net.LogManager.GetLogger(typeof(UserService));
        public UserService(IUserRepository userRepo, IMapper mapper, IConfiguration config)
        {
            _user = userRepo;
            _mapper = mapper;
            _config = config;
        }
        public async Task<bool> RegisterUserAsync(CreateUserDto userDetails)
        {
            try
            {
                var user = _mapper.Map<Users>(userDetails);
                bool respone = await _user.CreateUserAsync(user);
                return respone;
            }
            catch(Exception ex)
            {
                _log4net.Info(ex.Message);
                return false;
            }
        }

        public async Task<IEnumerable<ViewUserDto>> GetAllUsersAsync()
        {
            try
            {
                var users = await _user.GetAllUsersAsync();
                var userDetail = new List<ViewUserDto>();
                foreach (var user in users)
                {
                    userDetail.Add(_mapper.Map<ViewUserDto>(user));
                }
                return userDetail;
            }
            catch(Exception ex)
            {
                _log4net.Info(ex.Message);
                return null;
            }
            
        }

        public async Task<ViewUserDto> GetUserAsync(string userId)
        {
            try
            {
                var user = await _user.GetUserAsync(userId);
                return _mapper.Map<ViewUserDto>(user);
            }
            catch(Exception ex)
            {
                _log4net.Info(ex.Message);
                return null;
            }
            
        }

        public async Task<bool?> IsEmailIdAlreadyExist(string emailId)
        {
            try
            {
                return await _user.IsUserAlreadyExist(emailId);
            }
            catch(Exception ex)
            {
                _log4net.Info(ex.Message);
                return null;
            }
            
        }

        public async Task<ViewUserDto> UserLogin(UserCredentials credential)
        {
            var user = await _user.LoginUser(credential);
            if (user != null)
            {
                _log4net.Info("User Info is retreived");
                var tokenString = GenerateJSONWebToken(user);
                user.Token = tokenString;
                return _mapper.Map<ViewUserDto>(user);
            }
            _log4net.Info("User Info is null");
            return null;
        }

        public async Task<bool> ResetPassword(string userId, string newPassword)
        {
            var result = await _user.updatePassword(userId, newPassword);

            return result;
        }

        public async Task<bool> ValidateSecurityCredential(ResetPasswordDto credentilas)
        {
            var result = await _user.CheckSecurityCredential(credentilas);
            return result;
        }

        public string GenerateJSONWebToken(Users userInfo)
        {
            _log4net.Info("Token Is Generated!");

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
              issuer: _config["Jwt:Issuer"],
              audience: _config["Jwt:Issuer"],
              null,
              expires: DateTime.Now.AddMinutes(30),
              signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
