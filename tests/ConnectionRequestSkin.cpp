#include "Network/ConnectionRequest.h"

#include <openssl/evp.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
    void require(bool condition, const char *message) {
        if (!condition)
            throw std::runtime_error(message);
    }

    std::string base64(const std::string &value) {
        std::vector<unsigned char> out(4 * ((value.size() + 2) / 3) + 1);
        const int length = EVP_EncodeBlock(out.data(), (const unsigned char *) value.data(), (int) value.size());
        return std::string((const char *) out.data(), (size_t) length);
    }
}

int main() {
    try {
        const std::string clientData = "{\"SkinId\":\"fixture\",\"SkinImageWidth\":1,\"SkinImageHeight\":1,"
                                       "\"SkinData\":\"AAAA/w==\",\"ArmSize\":\"slim\",\"SkinColor\":\"#ffc89a7b\","
                                       "\"PersonaSkin\":true,\"OverrideSkin\":false,\"TrustedSkin\":true,"
                                       "\"ProfileHash\":\"fixture-hash\",\"PieceTintColors\":[{\"Colors\":"
                                       "[\"#ffa12722\",\"#FF2F1F0F\",\"#3aafd9\",\"#0\"],\"PieceType\":\"persona_eyes\"}]}";

        ConnectionRequest request;
        request.parse("", "e30." + base64(clientData) + ".");
        const SerializedSkin &skin = request.getSkin();

        require(skin.mColorArgb == (int32_t) 0xffc89a7bu, "skin colour lost");
        require(!skin.mArmsWide, "arm size lost");
        require(skin.mTintColors.size() == 1 && skin.mTintColors[0].mType == "eyes", "tint type lost");
        const std::vector<int32_t> expected = {(int32_t) 0xffa12722u, (int32_t) 0xff2f1f0fu, 0x003aafd9, 0};
        require(skin.mTintColors[0].mColors == expected, "tint colours lost");
        require(!skin.mOverridingPlayerAppearance, "override flag differs from the login");
        require(skin.mTrusted, "trusted flag differs from the login");
        require(!skin.mPrimaryUser, "primary user flag set");
        require(skin.mProfileHash == "fixture-hash", "profile hash lost");

        std::cout << "Login skin tests passed\n";
    } catch (const std::exception &error) {
        std::cout << "Login skin test failed: " << error.what() << '\n';
        return 1;
    }
}
