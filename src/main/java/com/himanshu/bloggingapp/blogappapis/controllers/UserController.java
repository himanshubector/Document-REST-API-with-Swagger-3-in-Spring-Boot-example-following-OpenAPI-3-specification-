package com.himanshu.bloggingapp.blogappapis.controllers;


import com.himanshu.bloggingapp.blogappapis.entities.User;
import com.himanshu.bloggingapp.blogappapis.payloads.CustomApiResponse;
import com.himanshu.bloggingapp.blogappapis.payloads.UserDto;
import com.himanshu.bloggingapp.blogappapis.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.*;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.antlr.v4.runtime.atn.SemanticContext;
import org.apache.coyote.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;


@Tag(name = "User", description = "User management APIs")
@RestController
@RequestMapping("/api/users")
public class UserController
{
    @Autowired
    private UserService userService;


    // POST - create user

    @PostMapping("/")
    public ResponseEntity<UserDto> createUser(@Valid @RequestBody UserDto userDto)
    {
        UserDto createUserDto = this.userService.createUser(userDto);

        return new ResponseEntity<>(createUserDto, HttpStatus.CREATED);

    }



    // PUT - update user

    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUser(@Valid @RequestBody UserDto userDto, @PathVariable Integer userId)
    {
        UserDto updatedUser = this.userService.updateUser(userDto, userId);
        return ResponseEntity.ok(updatedUser);

    }

   // OR

   // @PutMapping("/{userId}")
   // public ResponseEntity<UserDto> updateUser(@RequestBody UserDto userDto, @PathVariable("userId") Integer uid)




    // GET - get all users

    @GetMapping("/")
    public ResponseEntity<List<UserDto>> getAllUsers()
    {
        return ResponseEntity.ok(this.userService.getAllUsers());

    }



    // Refer ->  https://www.bezkoder.com/spring-boot-swagger-3/

   //  https://www.baeldung.com/spring-rest-openapi-documentation


    // GET - get single user

    @Operation(
            summary = "Retrieve a User by Id",
            description = "Get a User object by specifying its id. The response is User object with id, name, email and password.",
            tags = { "users", "get" })
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Found the user",
                    content = { @Content(mediaType = "application/json",
                            schema = @Schema(implementation = User.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid id supplied",
                    content = @Content),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content) })
    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> getSingleUser(@PathVariable Integer userId)
    {
        return ResponseEntity.ok(this.userService.getUserById(userId));

    }




    // DELETE - delete user

   /* @DeleteMapping("/{userId}")
    public ResponseEntity<UserDto> deleteUser(@RequestBody UserDto userDto, @PathVariable("userId") Integer uid)
    {
        this.userService.deleteUser(uid);
        return new ResponseEntity(Map.of("message","User Deleted Successfully"), HttpStatus.OK);
        // OR here we can also create an ApiResponse class to return the response to the user for this Delete User api

    }*/


    @DeleteMapping("/{userId}")
    public ResponseEntity<CustomApiResponse> deleteUserWithApiResponse(@RequestBody UserDto userDto, @PathVariable("userId") Integer uid)
    {
        this.userService.deleteUser(uid);
        return new ResponseEntity(new CustomApiResponse("User Deleted Successfully", true), HttpStatus.OK);

    }

}
