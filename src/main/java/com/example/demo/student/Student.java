package com.example.demo.student;

import lombok.*;

@ToString
@Getter
@Setter

@AllArgsConstructor
public class Student {
    private final Integer studentId;
    private final String studentName;
}
