package com.devdoc.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AwardDTO {
    private Integer id;
    private String awardName;
    private String awardingInstitution;
    private String date;
    private String description;

}