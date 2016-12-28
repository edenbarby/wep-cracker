/*
********************************************************************************
** @file   repo/wep-cracker/src/radiotap.h
** @author eden barby
** @date   28th december 2016
** @brief  
********************************************************************************
** external functions
********************************************************************************
** 
********************************************************************************
*/


#ifndef RADIOTAP_H
#define RADIOTAP_H


/* includes *******************************************************************/
/* external typedefs **********************************************************/
/* external defines ***********************************************************/
/* external macros ************************************************************/


class Radiotap
{
public:
    Radiotap();
    int init(const u_char *frame);
private:
    uint8_t version_;
    uint16_t length_;
    std::list<uint32_t> present_flags_;
};


#endif // RADIOTAP_H