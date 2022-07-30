using com.tweetapp.Models;
using com.tweetapp.Models.Dtos.UserDto;
using com.tweetapp.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace com.tweetapp.Controllers
{
    [Authorize]
    [Route("api/v1.0/tweets")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        private IConfiguration _config;
        static readonly log4net.ILog _log4net = log4net.LogManager.GetLogger(typeof(UserController));
        public UserController(IUserService userService, IConfiguration config)
        {
            _userService = userService;
            _config = config;
        }

        /// <summary>
        /// Login
        /// </summary>
        /// <param name="credentials"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserCredentials credentials)
        {
            var response = await _userService.UserLogin(credentials);
            _log4net.Info("Login initiated!");
            if (response != null)
            {
                return Ok(response);
            }
            return StatusCode(404, new { errorMessage = "Invalid Credentials!"});
        }

        /// <summary>
        /// Register new user
        /// </summary>
        /// <param name="userDetail"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] CreateUserDto userDetail)
        {
            bool? isEmailAlreadyExist = await _userService.IsEmailIdAlreadyExist(userDetail.EmailId);
            if (isEmailAlreadyExist!=null && isEmailAlreadyExist==true)
            {
                return StatusCode(400, new { error = $"{userDetail.EmailId} is already registered." });
            }
            else if(isEmailAlreadyExist == null)
            {
                return StatusCode(500, new { error = "Some internal error occurred!" });
            }
            var response = await _userService.RegisterUserAsync(userDetail);
            if(response == false)
            {
                return StatusCode(500, new { error = $"Some internal error occurred while registering the userid {userDetail.EmailId}" });
            }
            return StatusCode(201, new { userDetail.EmailId});
        }

        /// <summary>
        /// Get list of all users
        /// </summary>
        /// <returns></returns>
        [HttpGet("users/all")]
        public async Task<IActionResult> GetAllUsers()
        {
            var response = await _userService.GetAllUsersAsync();
            return Ok(response);
        }

        /// <summary>
        /// Get single user detail
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        [HttpGet("user/search/{userName}", Name = "GetUser")]
        public async Task<IActionResult> GetUser(string userName)
        {
            var response = await _userService.GetUserAsync(userName);
            if(response != null) { return Ok(response); }
            return StatusCode(404, new { error = $"{userName} not found!" });
        }

        /// <summary>
        /// Reset password
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="credentials"></param>
        /// <returns></returns>
        [HttpPut("resetPassword/{userId}")]
        public async Task<IActionResult> ResetPassword(string userId, [FromBody] ResetPasswordDto credentials)
        {
            var isUserExist = await _userService.IsEmailIdAlreadyExist(userId);
            if (isUserExist != null && isUserExist == true)
            {
                var response = await _userService.UserLogin(new UserCredentials { EmailId = userId, Password = credentials.OldPassword});
                if(response != null)
                {
                    var result = await _userService.ResetPassword(userId, credentials.NewPassword);
                    if (result)
                    {
                        return Ok(new { Message = "Passord reset successfull" });
                    }
                    else
                    {
                        return StatusCode(500, new { errorMessage = "Some internal error occured!" });
                    }
                }

            }
            return StatusCode(404, new { errorMessage = "UserId doesn't exist!" });
        }

        /// <summary>
        /// Verify Security credentials
        /// </summary>
        /// <param name="credentials"></param>
        /// <returns></returns>
        [HttpPut("forgot")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto credentials)
        {
            var isUserExist = await _userService.IsEmailIdAlreadyExist(credentials.EmailId);
            if (isUserExist != null && isUserExist == true)
            {
                var response = await _userService.ValidateSecurityCredential(credentials);
                return Ok(response);
            }
            return BadRequest();
        }

        /// <summary>
        /// Reset Forgotted Password
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        [HttpPut("reset/{userId}")]
        public async Task<IActionResult> UpdatePassword(string userId, [FromBody] ResetPasswordDto newPassword)
        {
            var result = await _userService.ResetPassword(userId, newPassword.NewPassword);
            return Ok(result);
        }
    }
}
